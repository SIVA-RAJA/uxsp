from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from uxsp.core.chunking import create_chunked_transfer, reassemble_chunked_transfer
from uxsp.core.envelope import Envelope
from uxsp.core.identity import Identity, PublicCard
from uxsp.crypto.symmetric import decrypt, encrypt
from uxsp.secure._context import _GLOBAL_CONTEXT
from uxsp.secure._errors import SecureReceiveError, TypeMismatchError
from uxsp.secure._package import SecurePackage
from uxsp.secure._utils import _normalize_id, _safe_is_file


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
        # Large payload chunking - session key approach
        session_key = os.urandom(32)
        env = sender_obj.seal_for(session_key, peer_card)
        chunks = create_chunked_transfer(payload_bytes, chunk_size=16 * 1024)
        sealed_chunks: list[dict[str, Any]] = []
        for seq, chunk_bytes in enumerate(chunks):
            ad = f"{env.envelope_nonce}:{seq}".encode()
            enc_dict = encrypt(chunk_bytes, session_key, associated_data=ad)
            sealed_chunks.append({
                "c": enc_dict["ciphertext"].hex(),
                "n": enc_dict["nonce"].hex(),
            })

        package = SecurePackage(
            sender_id=sender_obj.entity_id,
            receiver_id=rec_id,
            data_type=data_type,
            is_chunked=True,
            envelope=env.to_dict(),
            chunks=sealed_chunks,
            metadata=meta,
        )

    if output_file is not None:
        package.save(output_file)

    _GLOBAL_CONTEXT.dispatch_package(package)
    return package



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
        if package.envelope is None:
            raise SecureReceiveError("Package is marked chunked but missing session key envelope.")

        env = Envelope.from_dict(package.envelope)
        session_key = receiver_obj.open_from(env, peer_card, replay_guard=guard)

        raw_chunks: list[bytes] = []
        for seq, c_dict in enumerate(package.chunks):
            ad = f"{env.envelope_nonce}:{seq}".encode()
            ciphertext = bytes.fromhex(c_dict["c"])
            nonce = bytes.fromhex(c_dict["n"])
            c_bytes = decrypt(ciphertext, nonce, session_key, associated_data=ad)
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
