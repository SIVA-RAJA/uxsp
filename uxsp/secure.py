"""
uxsp.secure — Simple Developer Workflow for UXSP

Provides a Simple high-level API for developers.
All underlying complexities (PQC hybrid encryption, chunking, replay guards,
and envelope serialization) are handled automatically behind 1-line functions.

Specialized data types supported:
- Video (SendVideo, ReceiveVideo)
- Audio (SendAudio, ReceiveAudio)
- Photo / Image (SendPhoto, ReceivePhoto, SendImage, ReceiveImage)
- Text (SendText, ReceiveText)
- Document (SendDocument, ReceiveDocument, SendDoc, ReceiveDoc)
- PDF (SendPDF, ReceivePDF)
- File (SendFile, ReceiveFile)
- Binary (SendBinary, ReceiveBinary)
- JSON (SendJSON, ReceiveJSON)
- HTML (SendHTML, ReceiveHTML)
- Archive (SendArchive, ReceiveArchive, SendZip, ReceiveZip)
- Voice (SendVoice, ReceiveVoice)
- Location (SendLocation, ReceiveLocation)
- Contact (SendContact, ReceiveContact)
- Universal polymorphic (Send, Receive)
"""
from __future__ import annotations

import json
import mimetypes
import threading
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator, BinaryIO, cast

from uxsp.core.chunking import (
    create_chunked_transfer,
    reassemble_chunked_transfer,
)
from uxsp.core.envelope import Envelope
from uxsp.core.identity import Identity, PublicCard
from uxsp.core.nonce import MemoryNonceStore, NonceStore
from uxsp.core.payload import (
    UXSPPayload,
    pack_binary,
    pack_file,
    pack_text,
    unpack_text,
)
from uxsp.core.replay import ReplayGuard
from uxsp.storage.keystore import KeyStore, MemoryKeyStore

# ═════════════════════════════════════════════════════════════
# ERRORS
# ═════════════════════════════════════════════════════════════


class SecureError(Exception):
    """Base exception for all uxsp.secure operations."""


class SecureSendError(SecureError):
    """Raised when sending or packaging fails."""


class SecureReceiveError(SecureError):
    """Raised when receiving, opening, or verifying a package fails."""


class PeerNotFoundError(SecureError):
    """Raised when the target peer's PublicCard cannot be resolved."""


class TypeMismatchError(SecureReceiveError):
    """Raised when received payload type does not match the expected type."""


# ═════════════════════════════════════════════════════════════
# SECURE PACKAGE CONTAINER
# ═════════════════════════════════════════════════════════════


@dataclass
class SecurePackage:
    """
    Standard container for encrypted UXSP packages (single envelope or chunked).

    Can be serialized directly to JSON, saved to a file, transmitted over HTTP/WS,
    or passed into Receive* functions.
    """
    sender_id: str
    receiver_id: str
    data_type: str
    is_chunked: bool
    envelope: dict[str, Any] | None = None
    chunks: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert package to a dictionary."""
        return {
            "uxsp_package_version": "1.0",
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "data_type": self.data_type,
            "is_chunked": self.is_chunked,
            "envelope": self.envelope,
            "chunks": self.chunks,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int | None = None) -> str:
        """Serialize package to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, file_path: str | Path) -> Path:
        """Save package to a JSON file."""
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(indent=2), encoding="utf-8")
        return p

    to_file = save

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurePackage:
        """Construct package from a dictionary."""
        if not isinstance(data, dict):
            raise SecureReceiveError("Package data must be a dictionary.")
        return cls(
            sender_id=str(data.get("sender_id", "")),
            receiver_id=str(data.get("receiver_id", "")),
            data_type=str(data.get("data_type", "file")),
            is_chunked=bool(data.get("is_chunked", False)),
            envelope=data.get("envelope"),
            chunks=data.get("chunks", []),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str | bytes) -> SecurePackage:
        """Deserialize package from a JSON string or bytes."""
        try:
            if isinstance(json_str, bytes):
                json_str = json_str.decode("utf-8")
            data = json.loads(json_str)
            return cls.from_dict(data)
        except Exception as exc:
            raise SecureReceiveError(f"Failed to parse JSON package: {exc}") from exc

    @classmethod
    def from_file(cls, file_path: str | Path) -> SecurePackage:
        """Load package from a JSON file."""
        if not _safe_is_file(file_path):
            raise SecureReceiveError(f"Package file not found: {file_path}")
        p = Path(file_path)
        return cls.from_json(p.read_text(encoding="utf-8"))


# ═════════════════════════════════════════════════════════════
# GLOBAL CONTEXT & CONFIGURATION
# ═════════════════════════════════════════════════════════════


class SecureContext:
    """
    Manages local identities, peer public keys, replay guards, and defaults
    for the simplified secure workflow.
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._identity: Identity | None = None
        self._keystore: KeyStore = MemoryKeyStore()
        self._noncestore: NonceStore = MemoryNonceStore()
        self._replay_guard: ReplayGuard = ReplayGuard(self._noncestore)
        self._default_output_dir: Path = Path.cwd() / "downloads"
        self._transport_hook: Callable[[SecurePackage], Any] | None = None

    def configure(
        self,
        *,
        identity: Identity | None = None,
        keystore: KeyStore | None = None,
        noncestore: NonceStore | None = None,
        replay_guard: ReplayGuard | None = None,
        default_output_dir: str | Path | None = None,
        transport_hook: Callable[[SecurePackage], Any] | None = None,
    ) -> None:
        """Configure runtime defaults."""
        with self._lock:
            if identity is not None:
                self._identity = identity
                self._keystore.put(identity.public_card())
            if keystore is not None:
                self._keystore = keystore
                if self._identity is not None:
                    self._keystore.put(self._identity.public_card())
            if noncestore is not None:
                self._noncestore = noncestore
                self._replay_guard = ReplayGuard(noncestore)
            if replay_guard is not None:
                self._replay_guard = replay_guard
            if default_output_dir is not None:
                self._default_output_dir = Path(default_output_dir)
            if transport_hook is not None:
                self._transport_hook = transport_hook

    def get_identity(self) -> Identity:
        """Get or create the default identity."""
        with self._lock:
            if self._identity is None:
                self._identity = Identity.create(name="DefaultUser", role="client")
                self._keystore.put(self._identity.public_card())
            return self._identity

    def set_identity(self, identity: Identity) -> None:
        """Set the active local identity."""
        with self._lock:
            self._identity = identity
            self._keystore.put(identity.public_card())

    def register_peer(self, peer_card_or_identity: PublicCard | Identity) -> None:
        """Register a peer's public card."""
        with self._lock:
            if isinstance(peer_card_or_identity, Identity):
                card = peer_card_or_identity.public_card()
            else:
                card = peer_card_or_identity
            self._keystore.put(card)

    def get_peer(self, entity_id: str | int | PublicCard | Identity) -> PublicCard:
        """Retrieve a registered peer's PublicCard."""
        eid = _normalize_id(entity_id)
        with self._lock:
            card = self._keystore.get(eid)
            if card is None:
                raise PeerNotFoundError(
                    f"No public card registered for peer '{eid}'. "
                    f"Register peer using uxsp.secure.register_peer(card) first."
                )
            if isinstance(card, PublicCard):
                return card
            return card.card

    def revoke_peer(self, peer: str | int | PublicCard | Identity, reason: str = "Key compromised") -> PublicCard:
        """Mark a registered peer's PublicCard as revoked."""
        eid = _normalize_id(peer)
        card = self.get_peer(eid)
        card.revoke(reason=reason)
        with self._lock:
            self._keystore.put(card, overwrite=True)
        return card

    def get_replay_guard(self) -> ReplayGuard:
        """Get the active replay guard."""
        with self._lock:
            return self._replay_guard

    def get_default_output_dir(self) -> Path:
        """Get the default download output directory."""
        with self._lock:
            return self._default_output_dir

    def dispatch_package(self, package: SecurePackage) -> Any:
        """Dispatch a package via transport hook if configured."""
        with self._lock:
            hook = self._transport_hook
        if hook is not None:
            return hook(package)
        return package

    def reset(self) -> None:
        """Reset context state to clean defaults (useful in tests)."""
        with self._lock:
            self._identity = None
            self._keystore = MemoryKeyStore()
            self._noncestore = MemoryNonceStore()
            self._replay_guard = ReplayGuard(self._noncestore)
            self._default_output_dir = Path.cwd() / "downloads"
            self._transport_hook = None


_GLOBAL_CONTEXT = SecureContext()


def configure(**kwargs: Any) -> None:
    """Configure global context defaults."""
    _GLOBAL_CONTEXT.configure(**kwargs)


def get_context() -> SecureContext:
    """Return the global secure context."""
    return _GLOBAL_CONTEXT


def set_identity(identity: Identity) -> None:
    """Set the active local identity."""
    _GLOBAL_CONTEXT.set_identity(identity)


def get_identity() -> Identity:
    """Get the active local identity."""
    return _GLOBAL_CONTEXT.get_identity()


def register_peer(peer_card_or_identity: PublicCard | Identity) -> None:
    """Register a peer's public card or identity."""
    _GLOBAL_CONTEXT.register_peer(peer_card_or_identity)


def get_peer(entity_id: str | int | PublicCard | Identity) -> PublicCard:
    """Retrieve a registered peer's PublicCard."""
    return _GLOBAL_CONTEXT.get_peer(entity_id)


def reset_context() -> None:
    """Reset the global context."""
    _GLOBAL_CONTEXT.reset()


def create_identity(name: str, role: str = "CLIENT") -> Identity:
    """Create a brand-new Identity with a freshly generated hybrid keypair."""
    return Identity.create(name=name, role=role)


def rotate_keys(identity: Identity | None = None) -> Identity:
    """
    Generate a new hybrid keypair for an Identity while preserving entity_id.

    If identity is None, rotates the active global context identity and updates registered keys.
    """
    if identity is None:
        ident = _GLOBAL_CONTEXT.get_identity()
        ident.rotate_keys()
        _GLOBAL_CONTEXT.set_identity(ident)
        return ident
    return identity.rotate_keys()


def revoke_peer(peer: str | int | PublicCard | Identity, reason: str = "Key compromised") -> PublicCard:
    """Mark a registered peer's PublicCard as revoked."""
    return _GLOBAL_CONTEXT.revoke_peer(peer, reason=reason)


def verify_peer_validity(peer: str | int | PublicCard | Identity) -> None:
    """Verify that a peer's PublicCard is neither expired nor revoked."""
    try:
        card = get_peer(peer)
    except PeerNotFoundError:
        if isinstance(peer, PublicCard):
            card = peer
        elif isinstance(peer, Identity):
            card = peer.public_card()
        else:
            raise
    card.verify_validity()


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return Identity.hash_password(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against an Argon2id PHC string hash."""
    return Identity.verify_password(stored_hash, password)


def export_identity_encrypted(identity: Identity, password: str) -> str:
    """Export an Identity to an encrypted JSON string protected by password."""
    return identity.to_encrypted_json(password)


def import_identity_encrypted(encrypted_json: str | bytes, password: str) -> Identity:
    """Import an Identity from an encrypted JSON string protected by password."""
    return Identity.from_encrypted_json(encrypted_json, password)


# ═════════════════════════════════════════════════════════════
# INTERNAL CORE ENGINE — PACK, ENCRYPT, SEAL & CHUNKING
# ═════════════════════════════════════════════════════════════


def _normalize_id(entity_id: str | int | PublicCard | Identity) -> str:
    """Ensure entity ID is a non-empty string."""
    if isinstance(entity_id, (PublicCard, Identity)):
        return entity_id.entity_id
    norm = str(entity_id).strip()
    if not norm:
        raise ValueError("Entity ID cannot be empty.")
    return norm


def _safe_is_file(path_val: Any) -> bool:
    """Safely check if path_val is an existing file without raising OSError on long strings."""
    if not isinstance(path_val, (str, Path)):
        return False
    try:
        p = Path(path_val)
        return p.is_file()
    except (OSError, ValueError):
        return False


def _resolve_package_input(package_input: Any) -> SecurePackage:
    """Resolve a SecurePackage from diverse inputs (SecurePackage, dict, str, Path, bytes)."""
    if isinstance(package_input, SecurePackage):
        return package_input
    if isinstance(package_input, dict):
        return SecurePackage.from_dict(package_input)
    if isinstance(package_input, bytes):
        return SecurePackage.from_json(package_input)
    if isinstance(package_input, str):
        trimmed = package_input.strip()
        if trimmed.startswith("{"):
            return SecurePackage.from_json(trimmed)
    if isinstance(package_input, (str, Path)):
        if _safe_is_file(package_input):
            return SecurePackage.from_file(Path(package_input))
        raise SecureReceiveError(f"Package file not found: {package_input}")
    raise SecureReceiveError(f"Cannot resolve package from input of type {type(package_input).__name__}")


def _secure_send_payload(
    receiver_id: str | int | PublicCard | Identity | None = None,
    payload_bytes: bytes = b"",
    data_type: str = "file",
    *,
    sender_identity: Identity | None = None,
    sender: Identity | None = None,
    receiver: str | int | PublicCard | Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """
    Encrypt and seal packed payload bytes for receiver_id or receiver.
    Automatically uses standard Envelope for <= 64KB and Chunked Transfer for > 64KB.
    Can take sender identity and receiver PublicCard directly without global config.
    """
    rec_target = receiver if receiver is not None else receiver_id
    if rec_target is None:
        raise ValueError("Receiver identity or receiver_id must be provided.")

    if isinstance(rec_target, Identity):
        peer_card = rec_target.public_card()
        rec_id = rec_target.entity_id
    elif isinstance(rec_target, PublicCard):
        peer_card = rec_target
        rec_id = rec_target.entity_id
    else:
        rec_id = _normalize_id(rec_target)
        peer_card = _GLOBAL_CONTEXT.get_peer(rec_id)

    sender_obj = sender or sender_identity or _GLOBAL_CONTEXT.get_identity()
    meta = metadata or {}

    # Use single envelope for payloads <= 30 KiB to ensure sealed envelope stays under 64 KiB
    if len(payload_bytes) <= 30 * 1024:
        env = sender_obj.seal_for(payload_bytes, peer_card)
        package = SecurePackage(
            sender_id=sender_obj.entity_id,
            receiver_id=rec_id,
            data_type=data_type,
            is_chunked=False,
            envelope=env.to_dict(),
            metadata=meta,
        )
    else:
        # Large payload chunking
        chunks = create_chunked_transfer(payload_bytes, chunk_size=16 * 1024)
        sealed_chunks: list[dict[str, Any]] = []
        for chunk_bytes in chunks:
            chunk_env = sender_obj.seal_for(chunk_bytes, peer_card)
            sealed_chunks.append(chunk_env.to_dict())

        package = SecurePackage(
            sender_id=sender_obj.entity_id,
            receiver_id=rec_id,
            data_type=data_type,
            is_chunked=True,
            chunks=sealed_chunks,
            metadata=meta,
        )

    if output_file is not None:
        package.save(output_file)

    _GLOBAL_CONTEXT.dispatch_package(package)
    return package


def _secure_send_stream(
    receiver_id: str | int | PublicCard | Identity | None = None,
    file_path: str | Path | None = None,
    data_type: str = "file",
    *,
    sender_identity: Identity | None = None,
    sender: Identity | None = None,
    receiver: str | int | PublicCard | Identity | None = None,
    metadata: dict[str, Any] | None = None,
) -> Generator[SecurePackage, None, None]:
    """
    Encrypt and seal a large file directly from disk, yielding one SecurePackage per chunk.
    """
    from uxsp.core.chunking import create_chunked_stream_transfer
    
    rec_target = receiver if receiver is not None else receiver_id
    if rec_target is None:
        raise ValueError("Receiver identity or receiver_id must be provided.")

    if isinstance(rec_target, Identity):
        peer_card = rec_target.public_card()
        rec_id = rec_target.entity_id
    elif isinstance(rec_target, PublicCard):
        peer_card = rec_target
        rec_id = rec_target.entity_id
    else:
        rec_id = _normalize_id(rec_target)
        peer_card = _GLOBAL_CONTEXT.get_peer(rec_id)

    sender_obj = sender or sender_identity or _GLOBAL_CONTEXT.get_identity()
    meta = metadata or {}

    if not file_path:
        raise ValueError("file_path must be provided for streaming.")

    # Yield individual chunk packages
    chunk_stream = create_chunked_stream_transfer(file_path, chunk_size=16 * 1024, kind="binary")
    
    for chunk_bytes in chunk_stream:
        chunk_env = sender_obj.seal_for(chunk_bytes, peer_card)
        package = SecurePackage(
            sender_id=sender_obj.entity_id,
            receiver_id=rec_id,
            data_type=data_type,
            is_chunked=True,
            chunks=[chunk_env.to_dict()],
            metadata=meta,
        )
        yield package

def SendStream(
    receiver_id: str | int | PublicCard | Identity | None = None,
    file_path: str | Path | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    data_type: str = "file",
    metadata: dict[str, Any] | None = None,
) -> Generator[SecurePackage, None, None]:
    """Encrypt and stream a large file as a generator of SecurePackages."""
    return _secure_send_stream(
        receiver_id=receiver_id,
        file_path=file_path,
        data_type=data_type,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        metadata=metadata,
    )


def _secure_receive_payload(
    sender_id: str | int | PublicCard | Identity | None = None,
    package_input: Any = None,
    expected_type: str | None = None,
    *,
    receiver_identity: Identity | None = None,
    receiver: Identity | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
) -> bytes:
    """
    Verify, unseal, and assemble payload bytes from sender_id or sender.
    Enforces replay protection and verifies hybrid signatures.
    Can take receiver identity and sender PublicCard directly without global config.
    """
    snd_target = sender_card if sender_card is not None else (sender if sender is not None else sender_id)
    if snd_target is None:
        raise ValueError("Sender identity/card or sender_id must be provided.")

    if isinstance(snd_target, Identity):
        peer_card = snd_target.public_card()
        snd_id = snd_target.entity_id
    elif isinstance(snd_target, PublicCard):
        peer_card = snd_target
        snd_id = snd_target.entity_id
    else:
        snd_id = _normalize_id(snd_target)
        peer_card = _GLOBAL_CONTEXT.get_peer(snd_id)

    package = _resolve_package_input(package_input)
    receiver_obj = receiver or receiver_identity or _GLOBAL_CONTEXT.get_identity()
    guard = _GLOBAL_CONTEXT.get_replay_guard()

    if package.sender_id != snd_id:
        raise SecureReceiveError(
            f"Sender ID mismatch: expected '{snd_id}', package has '{package.sender_id}'"
        )
    if package.receiver_id != receiver_obj.entity_id:
        raise SecureReceiveError(
            f"Receiver ID mismatch: intended for '{package.receiver_id}', current identity is '{receiver_obj.entity_id}'"
        )

    if expected_type is not None and package.data_type != expected_type:
        raise TypeMismatchError(
            f"Data type mismatch: expected '{expected_type}', got '{package.data_type}'"
        )

    if not package.is_chunked:
        if package.envelope is None:
            raise SecureReceiveError("Package is marked non-chunked but missing envelope.")
        env = Envelope.from_dict(package.envelope)
        payload_bytes = receiver_obj.open_from(env, peer_card, replay_guard=guard)
        return payload_bytes
    else:
        if not package.chunks:
            raise SecureReceiveError("Package is marked chunked but contains no chunks.")
        raw_chunks: list[bytes] = []
        for chunk_env_dict in package.chunks:
            c_env = Envelope.from_dict(chunk_env_dict)
            c_bytes = receiver_obj.open_from(c_env, peer_card, replay_guard=guard)
            raw_chunks.append(c_bytes)

        _, reassembled = reassemble_chunked_transfer(raw_chunks)
        return reassembled


def _resolve_download_target(
    download_path: str | Path | None,
    default_filename: str,
) -> Path:
    """Resolve file destination path for downloaded content."""
    if download_path is None:
        out_dir = _GLOBAL_CONTEXT.get_default_output_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir / default_filename

    p = Path(download_path)
    if p.is_dir() or not p.suffix or str(download_path).endswith(("/", "\\")):
        p.mkdir(parents=True, exist_ok=True)
        return p / default_filename

    p.parent.mkdir(parents=True, exist_ok=True)
    return p


# ═════════════════════════════════════════════════════════════
# 14 SPECIALIZED DATA TYPES — SENDER & RECEIVER APIS
# ═════════════════════════════════════════════════════════════


# ── 1. VIDEO ──────────────────────────────────────────────────


def SendVideo(
    receiver_id: str | int | PublicCard | Identity | None = None,
    video_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send a video to receiver."""
    if isinstance(video_path_or_bytes, (str, Path)):
        if not _safe_is_file(video_path_or_bytes):
            raise SecureSendError(f"File not found: {video_path_or_bytes}")
        p = Path(video_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="video",
                metadata=metadata,
            )
        fname = filename or p.name or "video.mp4"
        ctype, _ = mimetypes.guess_type(str(p))
        packed = pack_file(p, content_type=ctype or "video/mp4")
    elif isinstance(video_path_or_bytes, (bytes, bytearray)):
        fname = filename or "video.mp4"
        packed = pack_binary(video_path_or_bytes, filename=fname, content_type="video/mp4")
    else:
        raise SecureSendError("video_path_or_bytes must be a file path (str/Path) or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="video",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveVideo(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save a video from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="video",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_video.mp4"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


# ── 2. AUDIO ──────────────────────────────────────────────────


def SendAudio(
    receiver_id: str | int | PublicCard | Identity | None = None,
    audio_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send audio to receiver."""
    if isinstance(audio_path_or_bytes, (str, Path)):
        if not _safe_is_file(audio_path_or_bytes):
            raise SecureSendError(f"File not found: {audio_path_or_bytes}")
        p = Path(audio_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="audio",
                metadata=metadata,
            )
        fname = filename or p.name or "audio.mp3"
        ctype, _ = mimetypes.guess_type(str(p))
        packed = pack_file(p, content_type=ctype or "audio/mpeg")
    elif isinstance(audio_path_or_bytes, (bytes, bytearray)):
        fname = filename or "audio.mp3"
        packed = pack_binary(audio_path_or_bytes, filename=fname, content_type="audio/mpeg")
    else:
        raise SecureSendError("audio_path_or_bytes must be a file path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="audio",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveAudio(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save audio from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="audio",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_audio.mp3"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


# ── 3. PHOTO / IMAGE ──────────────────────────────────────────


def SendPhoto(
    receiver_id: str | int | PublicCard | Identity | None = None,
    photo_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send a photo/image to receiver."""
    if isinstance(photo_path_or_bytes, (str, Path)):
        if not _safe_is_file(photo_path_or_bytes):
            raise SecureSendError(f"File not found: {photo_path_or_bytes}")
        p = Path(photo_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="photo",
                metadata=metadata,
            )
        fname = filename or p.name or "photo.jpg"
        ctype, _ = mimetypes.guess_type(str(p))
        packed = pack_file(p, content_type=ctype or "image/jpeg")
    elif isinstance(photo_path_or_bytes, (bytes, bytearray)):
        fname = filename or "photo.jpg"
        packed = pack_binary(photo_path_or_bytes, filename=fname, content_type="image/jpeg")
    else:
        raise SecureSendError("photo_path_or_bytes must be a file path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="photo",
        output_file=output_file,
        metadata=metadata,
    )


def ReceivePhoto(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save a photo/image from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="photo",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_photo.jpg"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


# Aliases for Image
SendImage = SendPhoto
ReceiveImage = ReceivePhoto


# ── 4. TEXT ───────────────────────────────────────────────────


def SendText(
    receiver_id: str | int | PublicCard | Identity | None = None,
    text: str = "",
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    encoding: str = "utf-8",
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    """Encrypt and send a text message to receiver."""
    if not isinstance(text, str):
        raise SecureSendError("text must be a string.")
    packed = pack_text(text, encoding=encoding)
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="text",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveText(
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
    Receive, decrypt, and return a text message from sender.
    If download_path is provided, also writes the text to that file.
    """
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="text",
    )
    text_content = unpack_text(raw_payload)
    if download_path is not None:
        target_file = _resolve_download_target(download_path, "received_text.txt")
        target_file.write_text(text_content, encoding="utf-8")
    return text_content


# ── 5. DOCUMENT ───────────────────────────────────────────────


def SendDocument(
    receiver_id: str | int | PublicCard | Identity | None = None,
    doc_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send a document to receiver."""
    if isinstance(doc_path_or_bytes, (str, Path)):
        if not _safe_is_file(doc_path_or_bytes):
            raise SecureSendError(f"File not found: {doc_path_or_bytes}")
        p = Path(doc_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="document",
                metadata=metadata,
            )
        fname = filename or p.name or "document.bin"
        ctype, _ = mimetypes.guess_type(str(p))
        packed = pack_file(p, content_type=ctype or "application/octet-stream")
    elif isinstance(doc_path_or_bytes, (bytes, bytearray)):
        fname = filename or "document.bin"
        packed = pack_binary(doc_path_or_bytes, filename=fname, content_type="application/octet-stream")
    else:
        raise SecureSendError("doc_path_or_bytes must be a file path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="document",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveDocument(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save a document from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="document",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_document.bin"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


SendDoc = SendDocument
ReceiveDoc = ReceiveDocument


# ── 6. PDF ────────────────────────────────────────────────────


def SendPDF(
    receiver_id: str | int | PublicCard | Identity | None = None,
    pdf_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send a PDF file to receiver."""
    if isinstance(pdf_path_or_bytes, (str, Path)):
        if not _safe_is_file(pdf_path_or_bytes):
            raise SecureSendError(f"File not found: {pdf_path_or_bytes}")
        p = Path(pdf_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="pdf",
                metadata=metadata,
            )
        fname = filename or p.name or "document.pdf"
        packed = pack_file(p, content_type="application/pdf")
    elif isinstance(pdf_path_or_bytes, (bytes, bytearray)):
        fname = filename or "document.pdf"
        packed = pack_binary(pdf_path_or_bytes, filename=fname, content_type="application/pdf")
    else:
        raise SecureSendError("pdf_path_or_bytes must be a file path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="pdf",
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
    """Receive, decrypt, and save a PDF from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="pdf",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received.pdf"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


# ── 7. GENERIC FILE ───────────────────────────────────────────


def SendFile(
    receiver_id: str | int | PublicCard | Identity | None = None,
    file_path_or_bytes: str | Path | bytes | bytearray | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    content_type: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send any file or file bytes to receiver."""
    if isinstance(file_path_or_bytes, (bytes, bytearray)):
        payload = UXSPPayload(
            kind="file",
            body=bytes(file_path_or_bytes),
            filename=filename or "file.bin",
            content_type=content_type or "application/octet-stream",
        )
        packed = payload.to_bytes()
    elif isinstance(file_path_or_bytes, (str, Path)):
        if not _safe_is_file(file_path_or_bytes):
            raise SecureSendError(f"File not found: {file_path_or_bytes}")
        p = Path(file_path_or_bytes)
        packed = pack_file(p, content_type=content_type)
    else:
        raise SecureSendError("file_path_or_bytes must be a path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="file",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveFile(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save a file from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="file",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_file.bin"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


# ── 8. BINARY ─────────────────────────────────────────────────


def SendBinary(
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
    """Encrypt and send raw binary data to receiver."""
    if not isinstance(data, (bytes, bytearray)):
        raise SecureSendError("data must be bytes or bytearray.")
    packed = pack_binary(data, filename=filename, content_type=content_type)
    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="binary",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveBinary(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: Any = None,
    *,
    download_path: str | Path | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> bytes:
    """
    Receive, decrypt, and return raw binary bytes from sender.
    If download_path is provided, also saves bytes to that path.
    """
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="binary",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    if download_path is not None:
        default_name = payload.filename or "received.bin"
        target_file = _resolve_download_target(download_path, default_name)
        target_file.write_bytes(payload.body)
    return payload.body


# ── 9. JSON ───────────────────────────────────────────────────


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


# ── 10. HTML ──────────────────────────────────────────────────


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


# ── 11. ARCHIVE / ZIP ─────────────────────────────────────────


def SendArchive(
    receiver_id: str | int | PublicCard | Identity | None = None,
    archive_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    filename: str | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send a zip/tar archive to receiver."""
    if isinstance(archive_path_or_bytes, (str, Path)):
        if not _safe_is_file(archive_path_or_bytes):
            raise SecureSendError(f"File not found: {archive_path_or_bytes}")
        p = Path(archive_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="archive",
                metadata=metadata,
            )
        fname = filename or p.name or "archive.zip"
        ctype, _ = mimetypes.guess_type(str(p))
        packed = pack_file(p, content_type=ctype or "application/zip")
    elif isinstance(archive_path_or_bytes, (bytes, bytearray)):
        fname = filename or "archive.zip"
        packed = pack_binary(archive_path_or_bytes, filename=fname, content_type="application/zip")
    else:
        raise SecureSendError("archive_path_or_bytes must be a file path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="archive",
        output_file=output_file,
        metadata=metadata,
    )


def ReceiveArchive(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save an archive from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="archive",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_archive.zip"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


SendZip = SendArchive
ReceiveZip = ReceiveArchive


# ── 12. VOICE NOTE ────────────────────────────────────────────


def SendVoice(
    receiver_id: str | int | PublicCard | Identity | None = None,
    voice_path_or_bytes: str | Path | bytes | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    duration_seconds: float | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage | Generator[SecurePackage, None, None]:
    """Encrypt and send a voice note/message to receiver."""
    meta = metadata or {}
    if duration_seconds is not None:
        meta["duration_seconds"] = duration_seconds

    if isinstance(voice_path_or_bytes, (str, Path)):
        if not _safe_is_file(voice_path_or_bytes):
            raise SecureSendError(f"File not found: {voice_path_or_bytes}")
        p = Path(voice_path_or_bytes)
        if p.stat().st_size > 64 * 1024 * 1024:
            return SendStream(
                receiver_id=receiver_id,
                file_path=p,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                data_type="voice",
                metadata=metadata,
            )
        packed = pack_file(p, content_type="audio/ogg")
    elif isinstance(voice_path_or_bytes, (bytes, bytearray)):
        packed = pack_binary(voice_path_or_bytes, filename="voice.ogg", content_type="audio/ogg")
    else:
        raise SecureSendError("voice_path_or_bytes must be a file path or bytes.")

    return _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=packed,
        data_type="voice",
        output_file=output_file,
        metadata=meta,
    )


def ReceiveVoice(
    sender_id: str | int | PublicCard | Identity | None = None,
    download_path: str | Path | None = None,
    package: Any = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path:
    """Receive, decrypt, and save a voice note from sender."""
    raw_payload = _secure_receive_payload(
        sender_id=sender_id,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        package_input=package,
        expected_type="voice",
    )
    payload = UXSPPayload.from_bytes(raw_payload)
    default_name = payload.filename or "received_voice.ogg"
    target_file = _resolve_download_target(download_path, default_name)
    target_file.write_bytes(payload.body)
    return target_file


# ── 13. LOCATION ──────────────────────────────────────────────


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


# ── 14. CONTACT ───────────────────────────────────────────────


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


# ── 15. POLYMORPHIC DISPATCHER ────────────────────────────────


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
            return SendVideo(receiver=rec, video_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "audio":
            return SendAudio(receiver=rec, audio_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"photo", "image"}:
            return SendPhoto(receiver=rec, photo_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "text":
            return SendText(receiver=rec, text=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"document", "doc"}:
            return SendDocument(receiver=rec, doc_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "pdf":
            return SendPDF(receiver=rec, pdf_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt in {"archive", "zip"}:
            return SendArchive(receiver=rec, archive_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "voice":
            return SendVoice(receiver=rec, voice_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "json":
            return SendJSON(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "html":
            return SendHTML(receiver=rec, html_content=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "contact":
            return SendContact(receiver=rec, contact_data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "binary":
            return SendBinary(receiver=rec, data=item, sender=snd, output_file=output_file, metadata=metadata)
        if dt == "file":
            return SendFile(receiver=rec, file_path_or_bytes=item, sender=snd, output_file=output_file, metadata=metadata)

    if isinstance(item, (str, Path)):
        if _safe_is_file(item):
            p = Path(item)
            ext = p.suffix.lower()
            if ext in {".mp4", ".mkv", ".avi", ".mov", ".webm"}:
                return SendVideo(receiver=rec, video_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".mp3", ".wav", ".aac", ".flac", ".m4a"}:
                return SendAudio(receiver=rec, audio_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}:
                return SendPhoto(receiver=rec, photo_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext == ".pdf":
                return SendPDF(receiver=rec, pdf_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".zip", ".tar", ".gz", ".7z", ".bz2"}:
                return SendArchive(receiver=rec, archive_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
            if ext in {".html", ".htm"}:
                return SendHTML(receiver=rec, html_content=p.read_text(encoding="utf-8"), sender=snd, output_file=output_file, metadata=metadata)
            if ext == ".json":
                return SendJSON(receiver=rec, data=json.loads(p.read_text(encoding="utf-8")), sender=snd, output_file=output_file, metadata=metadata)
            return SendFile(receiver=rec, file_path_or_bytes=p, sender=snd, output_file=output_file, metadata=metadata)
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
        return ReceiveFile(sender=snd, download_path=download_path, package=pkg, receiver=rec)
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


# ── 16. MULTI-GIGABYTE FILE STREAMING ─────────────────────────


def _iter_chunks_from_source(
    source: str | Path | BinaryIO | Iterable[bytes],
    chunk_size: int = 64 * 1024,
) -> Generator[bytes, None, None]:
    """Stream raw byte chunks from a file path, file descriptor, or byte generator."""
    if isinstance(source, (str, Path)):
        p = Path(source)
        if not p.is_file():
            raise SecureSendError(f"File not found: {source}")
        with open(p, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    elif hasattr(source, "read") and callable(source.read):
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            yield chunk
    elif isinstance(source, Iterable):
        for item in source:
            if item:
                yield bytes(item)
    else:
        raise SecureSendError("Source must be a file path, file descriptor (BinaryIO), or byte iterable.")


def SendStream(
    stream_or_path: str | Path | BinaryIO | Iterable[bytes],
    *,
    receiver_id: str | int | PublicCard | Identity | None = None,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    chunk_size: int = 64 * 1024,
    filename: str | None = None,
    output_destination: str | Path | BinaryIO | None = None,
    metadata: dict[str, Any] | None = None,
) -> Generator[SecurePackage, None, None] | Path | BinaryIO:
    """
    Encrypt and stream multi-gigabyte files or binary data generators chunk-by-chunk.

    Memory footprint is strictly O(chunk_size) to process 10GB+ files without high RAM usage.

    If output_destination is provided (file path or writable file descriptor), serializes line-delimited
    JSON packages directly to the output file/stream and returns output_destination.
    Otherwise, returns a Generator yielding SecurePackage objects chunk-by-chunk.
    """
    fname = filename
    if isinstance(stream_or_path, (str, Path)):
        fname = fname or Path(stream_or_path).name

    chunk_gen = _iter_chunks_from_source(stream_or_path, chunk_size=chunk_size)

    def _package_generator() -> Generator[SecurePackage, None, None]:
        has_yielded = False
        for chunk_idx, chunk_bytes in enumerate(chunk_gen):
            has_yielded = True
            chunk_meta = {
                "stream_chunk_index": chunk_idx,
                "stream_filename": fname or "stream.bin",
                **(metadata or {}),
            }
            pkg = SendBinary(
                receiver_id=receiver_id,
                data=chunk_bytes,
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                filename=fname,
                metadata=chunk_meta,
            )
            yield pkg

        if not has_yielded:
            chunk_meta = {
                "stream_chunk_index": 0,
                "stream_filename": fname or "stream.bin",
                **(metadata or {}),
            }
            pkg = SendBinary(
                receiver_id=receiver_id,
                data=b"",
                receiver=receiver,
                sender=sender,
                sender_identity=sender_identity,
                filename=fname,
                metadata=chunk_meta,
            )
            yield pkg

    if output_destination is None:
        return _package_generator()

    if isinstance(output_destination, (str, Path)):
        out_p = Path(output_destination)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            for pkg in _package_generator():
                f.write(pkg.to_json() + "\n")
        return out_p
    elif hasattr(output_destination, "write"):
        dest: Any = output_destination
        for pkg in _package_generator():
            line = pkg.to_json() + "\n"
            try:
                dest.write(line)
            except TypeError:
                dest.write(line.encode("utf-8"))
        return output_destination
    else:
        raise SecureSendError("output_destination must be a file path or writable file descriptor.")


def ReceiveStream(
    packages_or_stream: Iterable[SecurePackage | str | bytes] | str | Path | BinaryIO,
    output_file: str | Path | BinaryIO,
    *,
    sender_id: str | int | PublicCard | Identity | None = None,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> Path | int:
    """
    Stream-decrypt incoming SecurePackage chunks and write decrypted bytes directly to disk or a file descriptor.

    Memory footprint is O(chunk_size), making it safe to process multi-gigabyte (10GB+) files.

    Returns Path to output_file (if path was given) or total bytes written (if file descriptor was given).
    """
    out_fp: Any = None
    close_out = False
    out_path = None

    if isinstance(output_file, (str, Path)):
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_fp = open(out_path, "wb")  # noqa: SIM115
        close_out = True
    elif hasattr(output_file, "write"):
        out_fp = output_file
    else:
        raise ValueError("output_file must be a file path or writable file descriptor.")

    total_bytes_written = 0

    try:
        def _iter_packages() -> Generator[SecurePackage, None, None]:
            if isinstance(packages_or_stream, (str, Path)):
                p = Path(packages_or_stream)
                with open(p, encoding="utf-8") as f:
                    for line_item in f:
                        line_str = line_item.strip()
                        if line_str:
                            yield SecurePackage.from_json(line_str)
            elif hasattr(packages_or_stream, "read"):
                stream_obj: Any = packages_or_stream
                for raw_line in stream_obj:
                    if isinstance(raw_line, bytes):
                        line_str = raw_line.decode("utf-8").strip()
                    else:
                        line_str = str(raw_line).strip()
                    if line_str:
                        yield SecurePackage.from_json(line_str)
            elif isinstance(packages_or_stream, Iterable):
                for item in packages_or_stream:
                    if isinstance(item, SecurePackage):
                        yield item
                    elif isinstance(item, (str, bytes)):
                        s = item.decode("utf-8") if isinstance(item, bytes) else item
                        s = s.strip()
                        if s:
                            yield SecurePackage.from_json(s)
            else:
                raise ValueError("packages_or_stream must be an iterable, file path, or file descriptor.")

        for pkg in _iter_packages():
            decrypted_chunk = ReceiveBinary(
                sender_id=sender_id,
                package=pkg,
                sender=sender,
                sender_card=sender_card,
                receiver=receiver,
                receiver_identity=receiver_identity,
            )
            if out_fp is not None:
                out_fp.write(decrypted_chunk)
            total_bytes_written += len(decrypted_chunk)

    finally:
        if close_out and out_fp is not None:
            out_fp.close()

    if out_path is not None:
        return out_path
    return total_bytes_written

