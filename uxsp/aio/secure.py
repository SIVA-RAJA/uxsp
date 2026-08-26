"""
UXSP Async Secure Module (`uxsp.aio.secure`)

Provides high-performance asynchronous dispatchers for all 14 UXSP data types,
as well as universal polymorphic `Send` and `Receive` functions.

All CPU-bound cryptographic operations (PQC encapsulation/signing, Argon2id,
AES-GCM encryption/decryption) and disk I/O are automatically offloaded to worker
threads using `asyncio.to_thread` to ensure that ASGI event loops (FastAPI,
Starlette, Quart) and WebSocket connections remain non-blocking under heavy load.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.secure import (
    SecurePackage,
)
from uxsp.secure import (
    get_identity as _sync_get_identity,
)
from uxsp.secure import (
    get_peer as _sync_get_peer,
)
from uxsp.secure import (
    register_peer as _sync_register_peer,
)
from uxsp.secure import (
    reset_context as _sync_reset_context,
)
from uxsp.secure import (
    revoke_peer as _sync_revoke_peer,
)
from uxsp.secure import (
    rotate_keys as _sync_rotate_keys,
)
from uxsp.secure import (
    set_identity as _sync_set_identity,
)
from uxsp.secure import (
    verify_peer_validity as _sync_verify_peer_validity,
)


async def set_identity(identity: Identity) -> None:
    """Asynchronously set the active local identity."""
    await asyncio.to_thread(_sync_set_identity, identity)


async def get_identity() -> Identity:
    """Asynchronously get the active local identity."""
    return await asyncio.to_thread(_sync_get_identity)


async def register_peer(peer_card_or_identity: PublicCard | Identity) -> None:
    """Asynchronously register a peer's public card or identity."""
    await asyncio.to_thread(_sync_register_peer, peer_card_or_identity)


async def get_peer(entity_id: str | int) -> PublicCard:
    """Asynchronously retrieve a registered peer's PublicCard."""
    return await asyncio.to_thread(_sync_get_peer, entity_id)


async def reset_context() -> None:
    """Asynchronously reset the global context."""
    await asyncio.to_thread(_sync_reset_context)


async def rotate_keys(identity: Identity | None = None) -> Identity:
    """Asynchronously rotate hybrid keypair for an Identity."""
    return await asyncio.to_thread(_sync_rotate_keys, identity)


async def revoke_peer(peer: str | int | PublicCard | Identity, reason: str = "Key compromised") -> PublicCard:
    """Asynchronously mark a registered peer's PublicCard as revoked."""
    return await asyncio.to_thread(_sync_revoke_peer, peer, reason)


async def verify_peer_validity(peer: str | int | PublicCard | Identity) -> None:
    """Asynchronously verify that a peer's PublicCard is neither expired nor revoked."""
    await asyncio.to_thread(_sync_verify_peer_validity, peer)


# ── 1. VIDEO ──────────────────────────────────────────────────


async def SendVideo(
    receiver_id: str | int | PublicCard | Identity | None = None,
    video_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send a video file/bytes to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendVideo,
        receiver_id=receiver_id,
        video_path_or_bytes=video_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveVideo(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save video asset from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveVideo,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 2. AUDIO ──────────────────────────────────────────────────


async def SendAudio(
    receiver_id: str | int | PublicCard | Identity | None = None,
    audio_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send audio file/bytes to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendAudio,
        receiver_id=receiver_id,
        audio_path_or_bytes=audio_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveAudio(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save audio asset from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveAudio,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 3. PHOTO / IMAGE ──────────────────────────────────────────


async def SendPhoto(
    receiver_id: str | int | PublicCard | Identity | None = None,
    photo_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send a photo/image to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendPhoto,
        receiver_id=receiver_id,
        photo_path_or_bytes=photo_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceivePhoto(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save photo asset from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceivePhoto,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


SendImage = SendPhoto
ReceiveImage = ReceivePhoto


# ── 4. TEXT ───────────────────────────────────────────────────


async def SendText(
    receiver_id: str | int | PublicCard | Identity | None = None,
    text: str = "",
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send a text message to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendText,
        receiver_id=receiver_id,
        text=text,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveText(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> str:
    """Async: Receive and decrypt text message from sender."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveText,
        sender_id=sender_id,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 5. DOCUMENT ───────────────────────────────────────────────


async def SendDocument(
    receiver_id: str | int | PublicCard | Identity | None = None,
    doc_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send a document file/bytes to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendDocument,
        receiver_id=receiver_id,
        doc_path_or_bytes=doc_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveDocument(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save document asset from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveDocument,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


SendDoc = SendDocument
ReceiveDoc = ReceiveDocument


# ── 6. PDF ────────────────────────────────────────────────────


async def SendPDF(
    receiver_id: str | int | PublicCard | Identity | None = None,
    pdf_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send a PDF file/bytes to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendPDF,
        receiver_id=receiver_id,
        pdf_path_or_bytes=pdf_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceivePDF(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save PDF asset from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceivePDF,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 7. ARBITRARY FILE ─────────────────────────────────────────


async def SendFile(
    receiver_id: str | int | PublicCard | Identity | None = None,
    file_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    content_type: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send any arbitrary file/bytes to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendFile,
        receiver_id=receiver_id,
        file_path_or_bytes=file_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        content_type=content_type,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveFile(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save file asset from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveFile,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 8. BINARY ─────────────────────────────────────────────────


async def SendBinary(
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
    """Async: Encrypt and send raw binary data to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendBinary,
        receiver_id=receiver_id,
        data=data,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        content_type=content_type,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveBinary(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    download_path: str | Path | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> bytes:
    """Async: Receive, decrypt, and return raw binary bytes from sender."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveBinary,
        sender_id=sender_id,
        package=package,
        download_path=download_path,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 9. JSON ───────────────────────────────────────────────────


async def SendJSON(
    receiver_id: str | int | PublicCard | Identity | None = None,
    data: Any = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send JSON serializable object (dict/list) to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendJSON,
        receiver_id=receiver_id,
        data=data,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveJSON(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    download_path: str | Path | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Any:
    """Async: Receive, decrypt, and parse JSON payload into dict/list."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveJSON,
        sender_id=sender_id,
        package=package,
        download_path=download_path,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 10. HTML ──────────────────────────────────────────────────


async def SendHTML(
    receiver_id: str | int | PublicCard | Identity | None = None,
    html_content: str = "",
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send HTML content to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendHTML,
        receiver_id=receiver_id,
        html_content=html_content,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveHTML(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    download_path: str | Path | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> str:
    """Async: Receive and decrypt HTML string content."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveHTML,
        sender_id=sender_id,
        package=package,
        download_path=download_path,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 11. ARCHIVE / ZIP ─────────────────────────────────────────


async def SendArchive(
    receiver_id: str | int | PublicCard | Identity | None = None,
    archive_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send zip/archive file/bytes to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendArchive,
        receiver_id=receiver_id,
        archive_path_or_bytes=archive_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        filename=filename,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveArchive(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save zip/archive asset from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveArchive,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


SendZip = SendArchive
ReceiveZip = ReceiveArchive


# ── 12. VOICE ─────────────────────────────────────────────────


async def SendVoice(
    receiver_id: str | int | PublicCard | Identity | None = None,
    voice_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    duration_seconds: float | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send a voice memo to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendVoice,
        receiver_id=receiver_id,
        voice_path_or_bytes=voice_path_or_bytes,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        duration_seconds=duration_seconds,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveVoice(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Async: Receive, decrypt, and save voice memo from sender to disk."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveVoice,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 13. LOCATION ──────────────────────────────────────────────


async def SendLocation(
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
    """Async: Encrypt and send location coordinates to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendLocation,
        receiver_id=receiver_id,
        latitude=latitude,
        longitude=longitude,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        description=description,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveLocation(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> dict[str, Any]:
    """Async: Receive and decrypt location coordinates dictionary."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveLocation,
        sender_id=sender_id,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 14. CONTACT ───────────────────────────────────────────────


async def SendContact(
    receiver_id: str | int | PublicCard | Identity | None = None,
    contact_data: dict[str, Any] | str = "",
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Async: Encrypt and send contact vCard or dict to receiver."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.SendContact,
        receiver_id=receiver_id,
        contact_data=contact_data,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        output_file=output_file,
        metadata=metadata,
    )


async def ReceiveContact(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> dict[str, Any] | str:
    """Async: Receive and decrypt contact vCard or dictionary."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.ReceiveContact,
        sender_id=sender_id,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )


# ── 15. UNIVERSAL POLYMORPHIC DISPATCH ───────────────────────


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
) -> SecurePackage:
    """Async: Polymorphic dispatcher to automatically encrypt and send any payload type."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.Send,
        receiver_id=receiver_id,
        item=item,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        data_type=data_type,
        output_file=output_file,
        metadata=metadata,
    )


async def Receive(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Any:
    """Async: Polymorphic dispatcher to receive and decrypt any payload type."""
    import uxsp.secure as sync_secure

    return await asyncio.to_thread(
        sync_secure.Receive,
        sender_id=sender_id,
        download_path=download_path,
        package=package,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
    )
